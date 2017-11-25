
rule m3f4_171292f9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.171292f9c8800b12"
     cluster="m3f4.171292f9c8800b12"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy amonetize advml"
     md5_hashes="['187e327918078463d72ed19481706593','232a415ee1e682e97e670bc431ab899f','faaaaf33c947dc0e6ea95494ea36f501']"

   strings:
      $hex_string = { 6c676f43686f72642e4167656e74496e7374616c6c65722e50726f70657274696573004147454e545f52454749535452595f4b4559004d595f4441494c595f56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
