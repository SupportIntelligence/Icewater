import "hash"

rule m3e9_331396b3cee30912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.331396b3cee30912"
     cluster="m3e9.331396b3cee30912"
     cluster_size="13862 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="mailru malicious riskware"
     md5_hashes="['019413dce537fff3efcabe7a0a469b12', '009336d041304a361586c9efd82c32b3', '049ba49fbd9b32e1c6af2ee99c4532f0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(24714,1030) == "8d0ca0886a961b5ebddd0ce5f0e8edbd"
}

