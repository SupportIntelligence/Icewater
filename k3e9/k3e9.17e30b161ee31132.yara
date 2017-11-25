
rule k3e9_17e30b161ee31132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30b161ee31132"
     cluster="k3e9.17e30b161ee31132"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['6f3e33049c186be11406a4d1505586bd','74f3843e8a0065fbe3c8d6e67b160844','b75be5ad314e6e9e41564fa24fe18e71']"

   strings:
      $hex_string = { 8082ccc87777777800867c687044447800867f7870ccc4780087f7b8b0bcc478008fffc8bb0000780087f7bbfbb7777800087f22bb8888880008f76bb2b22220 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
