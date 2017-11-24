
rule m3e9_7114949c5ee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7114949c5ee30b12"
     cluster="m3e9.7114949c5ee30b12"
     cluster_size="210"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt diple"
     md5_hashes="['0166e27841fadc70917f05828dd19909','05d83a3af7f868ba253916d0243c1678','47c177ac559e954311cbf9f2f6aa2500']"

   strings:
      $hex_string = { 9b68eba94100eb138d45bc508d45cc506a02e8e08efeff83c40cc38d4ddce8988efeffc38b4de064890d000000005f5e5bc9c3558bec83ec18687635400064a1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
