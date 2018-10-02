
rule k2318_3711092eee210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3711092eee210b12"
     cluster="k2318.3711092eee210b12"
     cluster_size="303"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['8b78289a3c0543a2e2603d8d0149cca6cdf0e048','9d1d2b874bbc92bd7ea6ec732c8c947f6d4d2b15','18642cbb1fe839ef4348fc97147f4abd7fe2fd43']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3711092eee210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
