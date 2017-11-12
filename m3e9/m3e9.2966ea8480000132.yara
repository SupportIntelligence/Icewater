
rule m3e9_2966ea8480000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2966ea8480000132"
     cluster="m3e9.2966ea8480000132"
     cluster_size="7150"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik trojandownloader"
     md5_hashes="['000570b335a234b3ea0c641fe9783cf0','001100c78f4dfbcc6ee29b6c9ad130b9','027a6abee465297ee79f6517c5d2c5ac']"

   strings:
      $hex_string = { c00f896d0300008b451085c074308b1085d2742a3bd60f84580300008b45d825ff0000807907480d00ffffff40750f8bcee8a382ffff85c00f89360300008b45 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
