
rule m2319_3b9910e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b9910e9c8800b12"
     cluster="m2319.3b9910e9c8800b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['179e71c5a976b05db8fb20ff1fc44c8c','2d53388d21f81783ac7f8923f9893238','f65b3484214aa25de5f5a33c83f02647']"

   strings:
      $hex_string = { 6e742e676574456c656d656e74427949642827506c7573466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
