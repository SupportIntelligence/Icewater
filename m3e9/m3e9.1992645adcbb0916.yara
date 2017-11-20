
rule m3e9_1992645adcbb0916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1992645adcbb0916"
     cluster="m3e9.1992645adcbb0916"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob zusy"
     md5_hashes="['05d1aca580beddcce1d55792e12d533d','4b2e974817ee17b56decb5ffeffa6e42','e9170ab91b5c1a3ebbda2d7980a011e8']"

   strings:
      $hex_string = { 4041c8f21fc95b1850a833afcef90f4dc093c62b94dbc525e1e37d3e207eb4d1d04776047121a465383c6670619dcddebe27c31217d98378061d84f6ffec44fb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
