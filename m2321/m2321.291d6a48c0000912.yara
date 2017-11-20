
rule m2321_291d6a48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291d6a48c0000912"
     cluster="m2321.291d6a48c0000912"
     cluster_size="11"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['027ec6a6a36796cd2a737469fb0e0134','0cbf9bd43763dd272d8d0f34c6656544','fa2e48c1ba0e872521c2f2cc1e669e06']"

   strings:
      $hex_string = { c25be35ef173289ada150bca6ee5bc9e4e7d436d05e9dfce49dbc59db287f2cb6555f78c0d351688a26c7e809b66330410f51e926a987a0ae7142af3af00b7ac }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
