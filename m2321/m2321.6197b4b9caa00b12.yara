
rule m2321_6197b4b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.6197b4b9caa00b12"
     cluster="m2321.6197b4b9caa00b12"
     cluster_size="30"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik shipup"
     md5_hashes="['0cab1829f75dbe7342b8ea262b73badc','1e3a4d5d01d41501106b55fde82d365b','beb3f933a6003b043bb8693ff5ae094e']"

   strings:
      $hex_string = { d367cddac1200635a92b663e5837c22caa873139aca195e2304de1f5cffae4cb2778b429eead97110b54b9c07df9329e466de6488e5dfe4cbe453ddb7799c52e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
