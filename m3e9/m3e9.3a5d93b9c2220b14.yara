
rule m3e9_3a5d93b9c2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5d93b9c2220b14"
     cluster="m3e9.3a5d93b9c2220b14"
     cluster_size="201"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi viking"
     md5_hashes="['0128ee745e2b057972fd990a06575b09','02a99b36192496aee5bfd5126dc36b11','41d5bfc714929d23129107287a918a25']"

   strings:
      $hex_string = { a82e84af39053357d7f131508d358a71d0a9bd8c2ef887610260a6048674d73c4500a5480253d2c744429426f9080772118b26490f5e2c42ec675d8f8edef94e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
