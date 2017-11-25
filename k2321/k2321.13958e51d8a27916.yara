
rule k2321_13958e51d8a27916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13958e51d8a27916"
     cluster="k2321.13958e51d8a27916"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['44c971b2b79218d19f4657523aa8021e','5c48b2091476bc26f985b1b08a15e660','f42ba7984197bf6c0de8277738acb84d']"

   strings:
      $hex_string = { 54391b083b4f7e2de7b795dfc36750034b6d5209830569657ca620bdf09c569be62be45ba86f840a0db12967d2c5becfa4cde5f24c6a2e68818c8dfc6b0fd613 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
