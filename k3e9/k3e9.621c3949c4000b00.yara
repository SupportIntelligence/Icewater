
rule k3e9_621c3949c4000b00
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.621c3949c4000b00"
     cluster="k3e9.621c3949c4000b00"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob vetor"
     md5_hashes="['0523c39fd845c283866cd289d26ac145','423510c610102b3f475f12d2f2dfdfc8','db65c0ed335cbddc3a4709f036ac3225']"

   strings:
      $hex_string = { 00740069006f006e00200031003900390036002d003200300030003100000022017d0001004c006500670061006c00540072006100640065006d00610072006b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
