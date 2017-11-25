
rule k3e9_3c5f3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c5f3ac9c4000b14"
     cluster="k3e9.3c5f3ac9c4000b14"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy simbot backdoor"
     md5_hashes="['03c6aa8cb582a4fe9033676716995e17','2c9cc4bfae708d592424d45e7cef77ba','c4696c843bd2b6db18a1f374f70a074c']"

   strings:
      $hex_string = { 5400720061006e0073006c006100740069006f006e00000000000904b00450414444494e47585850414444494e4750414444494e47585850414444494e475041 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
