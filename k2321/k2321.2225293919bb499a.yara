
rule k2321_2225293919bb499a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2225293919bb499a"
     cluster="k2321.2225293919bb499a"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['05d0b0d5e2c2a36868437c2dc4153b1b','49db37f848cb0e48cf12c9c3cd199baa','f34b09a0653fb6210e645d3149a35494']"

   strings:
      $hex_string = { 4b7f6935b30787ad1746778662125164daed1695e0ecc89ade91dfb41df23cf949de2a33c69934f65b1a2338d29845bd96d44ec4c3cbd88ad1d748a35230ee2b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
