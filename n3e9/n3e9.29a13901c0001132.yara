import "hash"

rule n3e9_29a13901c0001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29a13901c0001132"
     cluster="n3e9.29a13901c0001132"
     cluster_size="2153 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="yakes kazy tobfy"
     md5_hashes="['a59c72b20403010c6cf46d071382e077', '9a904dea0e08be746e2a3c97ff602f33', '98dfc18c7954901e493e0148850149dd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(4096,1024) == "ecfdbacc30c86598f2c9c26becbde9ef"
}

