
rule m2319_3b9936e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b9936e9c8800b12"
     cluster="m2319.3b9936e9c8800b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['95cf1cebae050378be3d58339916f498','9910dd25d5c5af25a255f450d30a05b3','afdfa1f927fb92f347851bd38ad87656']"

   strings:
      $hex_string = { 656d656e74427949642827466f6c6c6f776572733127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a3c2f7363726970743e0a3c2f626f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
