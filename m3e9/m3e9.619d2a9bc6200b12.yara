
rule m3e9_619d2a9bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619d2a9bc6200b12"
     cluster="m3e9.619d2a9bc6200b12"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbna jorik"
     md5_hashes="['0601791012c35b97386a7907c86ec53d','2179ef83248a06c843a07f875fa41957','c974678273ed055942bda378ce53e8f8']"

   strings:
      $hex_string = { d9e0eff3a0798892929293ff90ff90ff04aedcf6231300000000000000000000000080f4f9f2f2f1b6a36ea60836a9b3b4b7b7dd1c408aadacaca021092a11f8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
