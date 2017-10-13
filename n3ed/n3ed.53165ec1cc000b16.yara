import "hash"

rule n3ed_53165ec1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.53165ec1cc000b16"
     cluster="n3ed.53165ec1cc000b16"
     cluster_size="1898 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['5a5915506a837af63f5ba15612e36ceb', '010ff8255c0c1aaeac66845beb077b65', '53259d175f8e2bb27b80390c5f230a06']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

