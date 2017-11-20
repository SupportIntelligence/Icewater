
rule i403_4d06c69986220b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i403.4d06c69986220b30"
     cluster="i403.4d06c69986220b30"
     cluster_size="400"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rootkit small zusy"
     md5_hashes="['02491cc14bc06e581e9fd2055c690ade','026f5d307ee839c013c90ae439569a8f','0ac33efbf469e76c251b6647be0484e7']"

   strings:
      $hex_string = { a1024d6d47657453797374656d526f7574696e6541646472657373001d0452746c496e6974556e69636f6465537472696e6700007d0350734c6f6f6b75705072 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
