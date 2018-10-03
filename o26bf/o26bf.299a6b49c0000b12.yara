
rule o26bf_299a6b49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bf.299a6b49c0000b12"
     cluster="o26bf.299a6b49c0000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="temonde malicious kryptik"
     md5_hashes="['476d020b7ae02d4d426ba60d1f6c28802c167596','eecc560026f6882532937e7079b47ec769d98bf9','ec8d1c7ffba42f8538df6b78d998329ee4439aeb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bf.299a6b49c0000b12"

   strings:
      $hex_string = { 636f64696e673d227574662d38223f3e0d0a3c617373656d626c79206d616e696665737456657273696f6e3d22312e302220786d6c6e733d2275726e3a736368 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
