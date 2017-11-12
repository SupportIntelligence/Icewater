import "hash"

rule n3e9_29366a49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29366a49c0000932"
     cluster="n3e9.29366a49c0000932"
     cluster_size="2464 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="barys gamarue lilu"
     md5_hashes="['801993afd3bc4be436c299d4f7dc055d', '0d754e4f07c40ebeaa2e18b702d3eddf', '1dce43eaec94aa606b138eb18685d63c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(200704,1024) == "01b20baab45567cd2ae288e7857c154d"
}

