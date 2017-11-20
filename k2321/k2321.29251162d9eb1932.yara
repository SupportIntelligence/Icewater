
rule k2321_29251162d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29251162d9eb1932"
     cluster="k2321.29251162d9eb1932"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys vbkrypt"
     md5_hashes="['24e7a21639ec6afd9b1d86999c2b2a71','7e059dae7ef7861e274a524042a82d93','f9dcead2b5d1aafefed89970db853169']"

   strings:
      $hex_string = { dc404a979f8ca1805f4408f845c75dd6c671265235eeb4e51a6ccb9bb12d7f1879d57723a3e4b84b6027398a2505dcd35a0b74aac15e6d03bebb19c55e55fcec }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
