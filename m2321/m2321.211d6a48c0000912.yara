
rule m2321_211d6a48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.211d6a48c0000912"
     cluster="m2321.211d6a48c0000912"
     cluster_size="41"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['144221926295a7056bf1f8cbb7c038da','2344ac7cc3a30decdf0094ef39a77f8a','7dccee62f68d6feee8114e7e593b85c0']"

   strings:
      $hex_string = { c25be35ef173289ada150bca6ee5bc9e4e7d436d05e9dfce49dbc59db287f2cb6555f78c0d351688a26c7e809b66330410f51e926a987a0ae7142af3af00b7ac }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
