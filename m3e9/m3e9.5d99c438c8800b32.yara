
rule m3e9_5d99c438c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5d99c438c8800b32"
     cluster="m3e9.5d99c438c8800b32"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader kryptik"
     md5_hashes="['01f5ee924ae7f2abba607148407875aa','43df7ecd220906a4e1ce1c839494894c','b930e97b6f6b3e9de6315676d03b6ace']"

   strings:
      $hex_string = { 006d006100740063006800200045007800740065006e00730069006f006e0020004c006100620065006c002c0041006e0073007500700070006f007200740065 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
