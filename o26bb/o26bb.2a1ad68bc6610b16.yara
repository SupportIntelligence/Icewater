
rule o26bb_2a1ad68bc6610b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2a1ad68bc6610b16"
     cluster="o26bb.2a1ad68bc6610b16"
     cluster_size="186"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious attribute dangerousobject"
     md5_hashes="['8e7b3a4518da822fc94775e13c59bb53bcd8ce43','3bffc8a3a17db4481d7e765a69c189f8afdfff74','27bc8e8d5e7f94ceafcd92518b13034b760536c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2a1ad68bc6610b16"

   strings:
      $hex_string = { e21314c7ea2048ba7bd5f49e4786f6d1d8584fa86ccd1127186eff36089c2b729655dcf030a51f5e448a4ab380eb061989c24699329df2680fb4cfefa3763181 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
