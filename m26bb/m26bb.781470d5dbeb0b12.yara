
rule m26bb_781470d5dbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.781470d5dbeb0b12"
     cluster="m26bb.781470d5dbeb0b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack malicious patched"
     md5_hashes="['99219935ec64276ce232687c3f3801c6606af257','6e127d7c2192e88ec589e400dc39d9087a3e9a53','850f8cdb2a2e6398e0d07fc38f8abf95582336b9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.781470d5dbeb0b12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
