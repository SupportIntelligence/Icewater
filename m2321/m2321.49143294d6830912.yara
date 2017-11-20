
rule m2321_49143294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.49143294d6830912"
     cluster="m2321.49143294d6830912"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['0b944b069ea840c01bca8d845847ad2c','2256b776d21704f00286a442de6814cb','d8b66d36d77b9d7fe2caec53844fbd73']"

   strings:
      $hex_string = { 2a5a2e55e95e1a0fce57a1c81d4782a51c95312187669a083f98fb34d93ce1e5bbd1f35b8ce2fd38c06813a09f24414b1920037d701bff65564befdebfec9e09 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
