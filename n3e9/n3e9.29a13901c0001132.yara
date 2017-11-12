import "hash"

rule n3e9_29a13901c0001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29a13901c0001132"
     cluster="n3e9.29a13901c0001132"
     cluster_size="15889 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="yakes kazy tobfy"
     md5_hashes="['0dc30a6f264ff0a6e1814e622c1a85e2', '0d12aea0414d14460ca2187e6faf96d0', '07804c9c519f144e6f235a66e33cf94f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(4096,1024) == "ecfdbacc30c86598f2c9c26becbde9ef"
}

