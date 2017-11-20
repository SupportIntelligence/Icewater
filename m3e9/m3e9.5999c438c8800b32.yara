
rule m3e9_5999c438c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5999c438c8800b32"
     cluster="m3e9.5999c438c8800b32"
     cluster_size="132"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader chbm"
     md5_hashes="['060459b389cde0ddac2722a1a7e9c6bc','0dd615578123664dbce669fee5357854','78deecbe15a22dba34096d2b33c6c4c1']"

   strings:
      $hex_string = { 00740020006d006100740063006800200045007800740065006e00730069006f006e0020004c006100620065006c002c0041006e0073007500700070006f0072 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
