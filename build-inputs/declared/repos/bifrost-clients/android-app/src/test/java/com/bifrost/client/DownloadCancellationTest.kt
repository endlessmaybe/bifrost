package com.bifrost.client
import java.io.*
import java.net.*
import java.security.MessageDigest
import java.util.concurrent.*
import java.util.concurrent.atomic.*
import org.junit.Test
import org.junit.Assert.*

class DownloadCancellationTest {
 @Test fun allConcurrentWritersStopBeforePartialFileIsDeleted() {
  val root=kotlin.io.path.createTempDirectory("bifrost-cancel-").toFile()
  val file=File(root,"partial.apk")
  val body=ByteArray(16*1024*1024)
  val digest=MessageDigest.getInstance("SHA-256").digest(body).joinToString(""){"%02x".format(it)}
  val waiting=CountDownLatch(3)
  val connections=AtomicInteger()
  val failure=AtomicReference<Throwable>()
  val owner=Thread {
   try {
    BifrostArtifactDownloader.download(file,body.size.toLong(),digest,{
     object:HttpURLConnection(URL("https://fixture.invalid/apk")) {
      var opened=false
      val start get()=getRequestProperty("Range").substringAfter("=").substringBefore("-").toInt()
      val end get()=getRequestProperty("Range").substringAfter("-").toInt()
      override fun connect(){}
      override fun disconnect(){if(opened){opened=false;connections.decrementAndGet()}}
      override fun usingProxy()=false
      override fun getResponseCode():Int{opened=true;connections.incrementAndGet();return 206}
      override fun getHeaderField(name:String?)=if(name=="Content-Range")"bytes $start-$end/${body.size}" else null
      override fun getContentLengthLong()=(end-start+1).toLong()
      override fun getInputStream():InputStream {
       if(start==0)return ByteArrayInputStream(body,0,4194304)
       return object:InputStream(){
        override fun read():Int {
         waiting.countDown()
         try{Thread.sleep(10000)}catch(_:InterruptedException){Thread.currentThread().interrupt();throw InterruptedIOException()}
         return 0
        }
       }
      }
     }
    })
   }catch(error:Throwable){failure.set(error)}
  }
  try {
   owner.start()
   assertTrue(waiting.await(5,TimeUnit.SECONDS))
   owner.interrupt();owner.join(5000)
   assertFalse(owner.isAlive)
   assertNotNull(failure.get())
   assertEquals(0,connections.get())
   assertFalse(file.exists())
  }finally{owner.interrupt();owner.join(5000);root.deleteRecursively()}
 }
}
