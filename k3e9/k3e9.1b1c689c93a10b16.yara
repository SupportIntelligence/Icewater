
rule k3e9_1b1c689c93a10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c689c93a10b16"
     cluster="k3e9.1b1c689c93a10b16"
     cluster_size="438"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta nestha hllp"
     md5_hashes="['016466c0e92b6c7653b5bee0623add2e','0165e41f3e3a3a25b7ae53a8b30ca021','0e914ec5661cc55619e44c98d3a0726e']"

   strings:
      $hex_string = { 740650e8afdbffff83c42c5e5bc39053ba949140000fb60ae30a4231db43d3e339c37cf1915bc3558bec33c08b55088a52f280fa0273098b4d088079f3017516 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
