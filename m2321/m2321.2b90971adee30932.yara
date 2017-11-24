
rule m2321_2b90971adee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b90971adee30932"
     cluster="m2321.2b90971adee30932"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery emotet pemalform"
     md5_hashes="['1ab52190a42ec1cf091bb85ee76ef430','29365f8a57aa158aca2087d9dcb4ccfa','cbf1fe9520b9bc44e5feac7f1d981d29']"

   strings:
      $hex_string = { a4befeb4bc18f86048774b3d57528b5dba01f56a397d27cd1556da05c3594e70f2c9f98662c6bfc5069efbaef695d002e7ca3e171a8aaa90db94dd54e5bf25d7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
