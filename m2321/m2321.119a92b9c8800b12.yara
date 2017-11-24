
rule m2321_119a92b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.119a92b9c8800b12"
     cluster="m2321.119a92b9c8800b12"
     cluster_size="123"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['00763ab12c0b921a516f7641f9bbb103','00a51af3208cded171c8765cd76e50bd','258392442b7c0afbe0d9834256b7cae7']"

   strings:
      $hex_string = { 33f873183dff564e995a6e20a49bb6494528f61c2e86feb15521750496cd5bb56a537e1d060e39e9e7c89a27cee5041e68980a596b7b0cc48d46da2da91b5867 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
