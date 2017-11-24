
rule m2321_4914e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4914e448c0000b32"
     cluster="m2321.4914e448c0000b32"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2a05548f2a87d49ca57efce91554b81b','4065dc4ffd393ffa660614d347f40908','e1821fec89470d34e1e060a2781be0f5']"

   strings:
      $hex_string = { 50d49675ebce01a9c24989045c078c9a331b9f9bfbe19c1c5784950279c5105315c8b729dca52a2d007383e03528e203e94e210540138d4a6d7ebdea46c90d94 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
