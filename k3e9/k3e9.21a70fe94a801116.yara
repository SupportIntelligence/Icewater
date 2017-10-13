import "hash"

rule k3e9_21a70fe94a801116
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.21a70fe94a801116"
     cluster="k3e9.21a70fe94a801116"
     cluster_size="39039 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="generickd androm backdoor"
     md5_hashes="['02e9bc6ea868cdc12a859f663d4116d1', '01da40c477c7dfb38e089fd4b17f0162', '022ac56435af95f4c75258df29453ead']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9728,1024) == "4ab982450c4169cb439580b13a70fedd"
}

