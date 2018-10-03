
rule k2318_33135deace210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33135deace210b12"
     cluster="k2318.33135deace210b12"
     cluster_size="140"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['784d7ecf463f85ed503efb6910f699d4f12d66b9','e17fc12c7ab4385542912d5a274bd2a100d46bcb','d84130cad1a44d669ff72d7c3a85eed397c8c747']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33135deace210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
