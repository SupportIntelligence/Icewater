
rule m3ed_13ab8595da539916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.13ab8595da539916"
     cluster="m3ed.13ab8595da539916"
     cluster_size="101"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cloudguard dnsunlocker malicious"
     md5_hashes="['00407af57d46f8e1e5a2f508e0f54af4','033df3a963d41b88104db0fe4c432d71','2532051e090dffbb21db3579a3c2fd78']"

   strings:
      $hex_string = { 3bd37c088bc299f7fb004603005604f605f8110310015e7414803930750f6a038d41015051e8da6dffff83c40c807dfc0074078b4df8836170fd8bc75f5bc9c3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
