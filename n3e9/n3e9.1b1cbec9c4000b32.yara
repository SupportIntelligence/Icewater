import "hash"

rule n3e9_1b1cbec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1cbec9c4000b32"
     cluster="n3e9.1b1cbec9c4000b32"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qvod jadtre viking"
     md5_hashes="['1ee7e9634f57750f6e94e4297e21c195', 'ac00bb5ec81433ed9bc06f9ab34dad66', 'bf5de51cb3a415974f0f7aff7733efcc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

