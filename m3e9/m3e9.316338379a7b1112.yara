
rule m3e9_316338379a7b1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338379a7b1112"
     cluster="m3e9.316338379a7b1112"
     cluster_size="296"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['008183e4987cff16e743d1ee5dfd465c','02d56539043872d4be42cc32801faf50','3689be4c37b0c99ec52c305a9dd2e885']"

   strings:
      $hex_string = { 62529d1ca71b941ac268a9edf1ad5f7033f742efeb3f64cc5cd2c8b98220f93cf683fa3bec783704e5de484ab59f580e8a16bb9b93a019fdf475314d6a889663 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
