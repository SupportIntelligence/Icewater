
rule n26bb_29966c60d8ba7b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.29966c60d8ba7b12"
     cluster="n26bb.29966c60d8ba7b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor malicious neoreklami"
     md5_hashes="['f87a289f74f70a783434e3a6f0115a329e2e2b1c','561e148eff1fcc79906443d11dcf520f3d2bb361','2954924bb94acfc170081e73444b1b37dab174e1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.29966c60d8ba7b12"

   strings:
      $hex_string = { f7d805c34f840c3d9d6d351fb87899edab0f9cc13bc11bc9410faf4db08b85d4feffff89088955aceb178855a3807da300740b525252ff1574204b0033d2ff45 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
