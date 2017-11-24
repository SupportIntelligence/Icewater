
rule m3e9_39228d4d86221132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.39228d4d86221132"
     cluster="m3e9.39228d4d86221132"
     cluster_size="30"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['0b1c5afa3c537728957d6002ac7c4c40','0ca63002290bf9956a12f1fb0dd39ac6','c3701a7720801ed3315ea430c69c8a98']"

   strings:
      $hex_string = { d4fed0feccfec8fe94fe90fe8cfe002f070800c001f4052b34fff4022b36ff0b32000800e759fcfe0bf80004004648fffbef38fffde60800c0013548ff000df5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
