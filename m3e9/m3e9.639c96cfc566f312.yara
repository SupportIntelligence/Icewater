import "hash"

rule m3e9_639c96cfc566f312
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.639c96cfc566f312"
     cluster="m3e9.639c96cfc566f312"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple madang rahack"
     md5_hashes="['c36603e0132ec15b5e193f28a561ad9c', '0dee950ca64ca947af86dd63063db798', 'df93ec3ccb689d6adce69086f0b077d8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(188000,1030) == "b0d7521531466420dcf3da22bbbd2221"
}

