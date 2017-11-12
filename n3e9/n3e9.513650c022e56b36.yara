
rule n3e9_513650c022e56b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.513650c022e56b36"
     cluster="n3e9.513650c022e56b36"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadadmin bundler downloadmin"
     md5_hashes="['18130831935319443149c3b2c5457322','aea4328b03fc77e2a29e131772950df7','f12d26fc2c7b6378eedf1a1c31d46289']"

   strings:
      $hex_string = { 76aae6ffac5c451387662892f0ed2b187320f6fd6836967d9ba82a42ddf762d2cfa4d665fba2e71ecc70e947517fc03871a10b0a9c3b4499058269c3276feac2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
