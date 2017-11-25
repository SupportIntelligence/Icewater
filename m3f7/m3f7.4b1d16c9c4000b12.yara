
rule m3f7_4b1d16c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b1d16c9c4000b12"
     cluster="m3f7.4b1d16c9c4000b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script autolike"
     md5_hashes="['7e0953f22ba56355aad54dc231ee2f6e','938c8c6659cdc15e2be31f59f64936ce','a83216f9bbc9e8ac19864161fe158ba3']"

   strings:
      $hex_string = { 42794964282248544d4c312229293b27207461726765743d27636f6e66696748544d4c3127207469746c653d274368e1bb896e682073e1bbad61273e0a3c696d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
