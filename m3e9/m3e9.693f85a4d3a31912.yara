
rule m3e9_693f85a4d3a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85a4d3a31912"
     cluster="m3e9.693f85a4d3a31912"
     cluster_size="433"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['01d0963c1a205d65dd917b3c21f12740','0acf638e9ffa0e1392f28a4210268556','2e0d0322cb6b9367b3a9f13189a55630']"

   strings:
      $hex_string = { 62529d1ca71b941ac268a9edf1ad5f7033f742efeb3f64cc5cd2c8b98220f93cf683fa3bec783704e5de484ab59f580e8a16bb9b93a019fdf475314d6a889663 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
