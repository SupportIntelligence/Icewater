
rule m3e9_316338764abb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338764abb1112"
     cluster="m3e9.316338764abb1112"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['09b881f3f86b240241dd2880df2924c2','0ec35a6e4864d5800186a9e2152ab074','ea8d76cffe6c8de3d7458a33e3b0f6b7']"

   strings:
      $hex_string = { 62529d1ca71b941ac268a9edf1ad5f7033f742efeb3f64cc5cd2c8b98220f93cf683fa3bec783704e5de484ab59f580e8a16bb9b93a019fdf475314d6a889663 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
