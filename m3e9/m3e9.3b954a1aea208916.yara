
rule m3e9_3b954a1aea208916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3b954a1aea208916"
     cluster="m3e9.3b954a1aea208916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['36548d4a5d1d4e41799061317a979433','a6e12c107d8241b4cdd7a37737885dd4','eb27b566380d81b169a13f3257cc8897']"

   strings:
      $hex_string = { 70d9c5b55bb93e31518aaca6e0f36956e491a377df1ee19b6f20b8bed4adf4ce768debe97329b7f7c67dfc4e0a0d28ba4855a9fdd897afc426dc227ff00bcf89 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
