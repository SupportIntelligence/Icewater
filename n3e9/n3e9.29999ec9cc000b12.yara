
rule n3e9_29999ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29999ec9cc000b12"
     cluster="n3e9.29999ec9cc000b12"
     cluster_size="541"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softonic bundler softonicdownloader"
     md5_hashes="['01458238a315733f96a560a9ea5313fd','01866c070286441e7eea87b34f927294','082986b48ee699efa3380b2a44d96882']"

   strings:
      $hex_string = { abafe7a1c2a0fd539af977052e716f681f64d8c3f173fa8c9685a3c961297d9db2136936254a3ba761c7f7f0beca3526de5e561519c5a6d4f3418bd6bc332f17 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
