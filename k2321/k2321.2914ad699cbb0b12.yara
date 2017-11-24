
rule k2321_2914ad699cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad699cbb0b12"
     cluster="k2321.2914ad699cbb0b12"
     cluster_size="94"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['0053b46d8e9ba861afc744a3d7f543b5','007005a7b6df7db8e2d403c3882497a4','2a264c8536ce0e3643cfabfb8749e7f7']"

   strings:
      $hex_string = { c19b69823787f3df1cc67f6308efcd21dc5d43b86fa47276a572de48e1bc41f4e4ec18c8de3180b3a33f7bd700d61bfd985bfab0e727f232a2c5a991daf8f020 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
