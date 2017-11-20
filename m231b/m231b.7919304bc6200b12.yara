
rule m231b_7919304bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.7919304bc6200b12"
     cluster="m231b.7919304bc6200b12"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['052fcb5040300b247f94dd07950e0f5f','282c8268ac212f7cf5a7567684bb615b','c83a68947d7db63e6ee28246b6c97f83']"

   strings:
      $hex_string = { 38353930323831364334343346464141394438314637323334394445364331393735393246364342373141354135383036424430453135343233453637363230 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
