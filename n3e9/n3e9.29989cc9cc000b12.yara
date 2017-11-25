
rule n3e9_29989cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29989cc9cc000b12"
     cluster="n3e9.29989cc9cc000b12"
     cluster_size="137"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softonic softonicdownloader unwanted"
     md5_hashes="['038a10bbeec52c52666892c1f507833f','03d741a6e22275bd4a823219be051bbd','26867d56fae9050e5b0f29eea6d7c777']"

   strings:
      $hex_string = { abafe7a1c2a0fd539af977052e716f681f64d8c3f173fa8c9685a3c961297d9db2136936254a3ba761c7f7f0beca3526de5e561519c5a6d4f3418bd6bc332f17 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
