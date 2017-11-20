
rule m2321_0b193949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b193949c4000b12"
     cluster="m2321.0b193949c4000b12"
     cluster_size="141"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['0077b4d5136d5fdb96e207860a82d91e','01b3ed2ed1121df3f0e181c5ef71d2fd','1beffa161702f9f862fc32e212727b0e']"

   strings:
      $hex_string = { 4b7f6935b30787ad1746778662125164daed1695e0ecc89ade91dfb41df23cf949de2a33c69934f65b1a2338d29845bd96d44ec4c3cbd88ad1d748a35230ee2b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
